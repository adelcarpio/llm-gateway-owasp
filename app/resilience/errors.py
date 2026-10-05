"""Taxonomia de errores upstream y respuestas RFC 9457 (problem+json)."""
from __future__ import annotations

from fastapi.responses import JSONResponse


class UpstreamError(Exception):
    status: int = 502
    code: str = "UPSTREAM_UNAVAILABLE"
    outcome: str = "upstream_error"
    detail: str = "Proveedor no disponible temporalmente."


class UpstreamTimeout(UpstreamError):
    status, code, outcome = 504, "UPSTREAM_TIMEOUT", "upstream_timeout"
    detail = "El proveedor no respondio a tiempo."


class UpstreamSaturated(UpstreamError):
    status, code, outcome = 503, "UPSTREAM_SATURATED", "upstream_error"
    detail = "Capacidad del proveedor agotada temporalmente. Reintente mas tarde."


class UpstreamAuthError(UpstreamError):
    # Se presenta al cliente igual que un 5xx: no se revela que el gateway
    # tiene un problema con SU credencial. Se alerta al operador via log.
    outcome = "upstream_auth_error"


class CircuitOpen(UpstreamError):
    status, code, outcome = 503, "CIRCUIT_OPEN", "circuit_open"
    detail = "Servicio degradado. Reintente mas tarde."


def problem(status: int, code: str, detail: str, request_id: str,
            headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        headers=headers,
        content={
            "type": f"https://gateway.local/errors/{code.lower()}",
            "title": code,
            "status": status,
            "code": code,
            "detail": detail,
            "request_id": request_id,
        },
    )
