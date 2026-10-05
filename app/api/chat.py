"""Unico punto de entrada a los LLM: POST /v1/chat.

Pipeline: auth -> cuota (LLM10) -> esquema -> sanitizacion (LLM01) -> prompt (LLM07 canary)
-> proveedor (resiliencia) -> guardia de salida (LLM07) -> auditoria (LLM02).
"""
from __future__ import annotations

import json
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.api.schemas import LaxChatRequest, StrictChatRequest
from app.observability.secure_logger import AuditEvent, audit, naive_dump
from app.resilience.errors import UpstreamError, problem
from app.security.output_guard import NEUTRAL_RESPONSE
from app.security.sanitizer import sanitize

router = APIRouter()


@router.post("/v1/chat")
async def chat(request: Request):
    st = request.app.state
    settings = st.settings
    started = time.perf_counter()
    request_id = uuid.uuid4().hex[:16]
    ctx: dict = {"client_id": None, "rule_id": None, "prompt_chars": None,
                 "upstream_latency_ms": None, "tokens_in": None, "tokens_out": None,
                 "model": None}

    def finish(status: int, outcome: str) -> None:
        audit(AuditEvent(request_id=request_id, route="/v1/chat", method="POST", status=status,
                         outcome=outcome, provider=settings.upstream_provider,
                         latency_ms=int((time.perf_counter() - started) * 1000),
                         profile=settings.gateway_profile, **ctx))

    def fail(status: int, code: str, detail: str, outcome: str, headers=None) -> JSONResponse:
        finish(status, outcome)
        return problem(status, code, detail, request_id, headers)

    raw = await request.body()

    # --- LLM10: tamano de cuerpo ---------------------------------------------
    if settings.rate_limit_on and len(raw) > settings.max_body_bytes:
        return fail(413, "PAYLOAD_TOO_LARGE", "El cuerpo excede el tamano permitido.",
                    "rejected_schema")

    # --- Autenticacion -------------------------------------------------------
    identity = st.registry.authenticate(request.headers.get("x-gateway-key"))
    if identity is None:
        return fail(401, "UNAUTHORIZED", "Credencial de gateway invalida.", "rejected_auth")
    ctx["client_id"] = identity.client_id

    # --- LLM10: cuota por client_id (no por IP) ------------------------------
    rate_headers: dict[str, str] = {}
    if settings.rate_limit_on:
        decision = st.limiter.hit(identity.client_id)
        rate_headers = {"X-RateLimit-Limit": str(decision.limit),
                        "X-RateLimit-Remaining": str(decision.remaining)}
        if not decision.allowed:
            return fail(429, "RATE_LIMITED",
                        f"Limite alcanzado. Reintente en {decision.retry_after} s.",
                        "blocked_rate_limit",
                        {**rate_headers, "Retry-After": str(decision.retry_after)})

    # --- Esquema --------------------------------------------------------------
    model_cls = StrictChatRequest if settings.sanitizer_on else LaxChatRequest
    try:
        payload = model_cls.model_validate(json.loads(raw or b"{}"))
    except (ValidationError, ValueError):
        return fail(422, "INVALID_REQUEST", "La solicitud no cumple el esquema.", "rejected_schema")
    messages = [m.model_dump() for m in payload.messages]
    if settings.rate_limit_on and len(messages) > settings.max_messages:
        return fail(422, "INVALID_REQUEST", "Demasiados mensajes.", "rejected_schema")
    ctx["prompt_chars"] = sum(len(m["content"]) for m in messages)

    # --- LLM01: sanitizacion ---------------------------------------------------
    if settings.sanitizer_on:
        clean = []
        for m in messages:
            if m["role"] == "user":
                result = sanitize(m["content"], settings.max_input_chars)
                if not result.allowed:
                    ctx["rule_id"] = result.rule_id
                    return fail(400, "INPUT_REJECTED",
                                "La solicitud no cumple la politica de uso.", "blocked_input")
                m = {**m, "content": result.normalized_text}
            clean.append(m)
        messages = clean

    # --- max_tokens -----------------------------------------------------------
    requested = payload.max_tokens or settings.max_output_tokens
    max_tokens = min(requested, settings.max_output_tokens) if settings.rate_limit_on else requested

    # --- Prompt + proveedor ----------------------------------------------------
    built = st.prompt_builder.build(messages, spotlight=settings.sanitizer_on)
    t0 = time.perf_counter()
    try:
        result = await st.provider.complete(built.system, built.messages, max_tokens)
    except UpstreamError as exc:
        ctx["upstream_latency_ms"] = int((time.perf_counter() - t0) * 1000)
        if exc.outcome == "upstream_auth_error":
            st.ops_log.error("ALERTA: el proveedor rechazo la credencial del gateway (request_id=%s)",
                             request_id)
        return fail(exc.status, exc.code, exc.detail, exc.outcome)
    except Exception:
        ctx["upstream_latency_ms"] = int((time.perf_counter() - t0) * 1000)
        finish(500, "internal_error")
        if not settings.safe_logging_on:
            naive_dump(dict(request.headers), messages, None)
        raise  # baseline: debug=True expone la traza; secure: handler generico
    ctx["upstream_latency_ms"] = int((time.perf_counter() - t0) * 1000)
    ctx.update(model=result.model, tokens_in=result.tokens_in, tokens_out=result.tokens_out)

    body = {"request_id": request_id, "model": result.model, "content": result.text,
            "usage": {"tokens_in": result.tokens_in, "tokens_out": result.tokens_out}}
    outcome = "allowed"

    # --- LLM07: guardia de salida ----------------------------------------------
    if settings.output_guard_on:
        decision = st.output_guard.inspect(result.text)
        if not decision.allowed:
            body.update(content=NEUTRAL_RESPONSE, code="OUTPUT_FILTERED", filtered=True)
            outcome = "blocked_output_leak"

    if not settings.safe_logging_on:
        naive_dump(dict(request.headers), messages, result.text)
    finish(200, outcome)
    return JSONResponse(body, headers={**rate_headers, "X-Request-ID": request_id})
