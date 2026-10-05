"""Logging estructurado seguro (LLM02).

Barrera 1 - ALLOWLIST: el evento de auditoria es un modelo tipado con campos fijos
(`extra="forbid"`). Un campo no declarado (prompt, headers, key) NO puede escribirse.
Barrera 2 - REDACCION: un filtro enmascara patrones de credenciales en cualquier
registro que llegue al sink (incluidas trazas internas).

Nunca se registra: contenido de prompt/respuesta, API keys, cabeceras de autorizacion,
system prompt, fragmento que disparo una regla, ni hash plano del prompt.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.config import Settings

Outcome = Literal["allowed", "blocked_rate_limit", "blocked_input", "blocked_output_leak",
                  "rejected_auth", "rejected_schema", "upstream_timeout", "upstream_error",
                  "upstream_auth_error", "circuit_open", "internal_error"]


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: Literal["llm_request"] = "llm_request"
    request_id: str
    client_id: str | None = None
    route: str
    method: str
    status: int
    outcome: Outcome
    rule_id: str | None = None
    provider: str | None = None
    model: str | None = None
    latency_ms: int
    upstream_latency_ms: int | None = None
    prompt_chars: int | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    profile: str


_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(x-api-key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(x-gateway-key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9._\-]{8,}"),
]


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: (m.group(1) if m.groups() else "") + "[REDACTED]", text)
    return text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if record.exc_info:
            message += "\n" + logging.Formatter().formatException(record.exc_info)
            record.exc_info = None
            record.exc_text = None
        record.msg, record.args = redact(message), None
        return True


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                   "level": record.levelname, "logger": record.name}
        audit = getattr(record, "audit", None)
        if isinstance(audit, dict):
            payload.update(audit)
        else:
            payload["msg"] = record.getMessage()
            if record.exc_info:
                payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(settings: Settings) -> None:
    Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [logging.FileHandler(settings.log_file, encoding="utf-8"),
                                       logging.StreamHandler(sys.stdout)]
    for h in handlers:
        h.setFormatter(JsonLineFormatter())
        if settings.safe_logging_on:
            h.addFilter(RedactionFilter())

    for name in ("gateway.audit", "gateway.ops", "gateway.naive"):
        lg = logging.getLogger(name)
        for old in list(lg.handlers):
            lg.removeHandler(old)
            old.close()
        lg.propagate = False
        lg.setLevel(logging.INFO)
        if name == "gateway.naive" and settings.safe_logging_on:
            lg.disabled = True  # el logger ingenuo no existe en el perfil seguro
            continue
        lg.disabled = False
        for h in handlers:
            lg.addHandler(h)


def audit(event: AuditEvent) -> None:
    logging.getLogger("gateway.audit").info("llm_request", extra={"audit": event.model_dump()})


def naive_dump(request_headers: dict, body: object, response_text: str | None) -> None:
    """LINEA BASE VULNERABLE: lo que NO debe hacerse. Solo activo en baseline."""
    logging.getLogger("gateway.naive").info(
        "request headers=%s body=%s response=%s", request_headers, body, response_text)
