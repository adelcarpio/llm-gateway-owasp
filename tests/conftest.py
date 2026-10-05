"""Fixtures: gateway en proceso + mock upstream en proceso (sin red, determinista).

Cada test de seguridad se ejecuta en ambos perfiles:
  - baseline: el test AFIRMA que el ataque tiene exito (linea base valida).
  - secure:   el test AFIRMA que el ataque se bloquea.
La evidencia de cada ejecucion se guarda en evidence/<fecha>/.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from app.config import Settings
from app.main import create_app
from app.security.auth import hash_key
from mock_upstream.app import STATE as MOCK_STATE
from mock_upstream.app import app as mock_app

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence" / datetime.now(timezone.utc).strftime("%Y-%m-%d")
# Credencial FICTICIA con formato realista (para que los escaneres la detecten en la linea base).
FAKE_UPSTREAM_KEY = "sk-ant-api03-" + "x" * 93 + "AA"


@pytest.fixture
def keys():
    pepper = secrets.token_hex(16)
    a, b = "gk_" + secrets.token_urlsafe(24), "gk_" + secrets.token_urlsafe(24)
    return {"pepper": pepper, "A": a, "B": b,
            "hashes": f"cliente_a:{hash_key(pepper, a)},cliente_b:{hash_key(pepper, b)}"}


@pytest.fixture(autouse=True)
def reset_mock():
    MOCK_STATE.update(calls=0, mode="ok", timeout_seconds=2.0)
    yield
    MOCK_STATE.update(calls=0, mode="ok")


def make_settings(profile: str, keys: dict, log_file: Path, **overrides) -> Settings:
    base = dict(
        _env_file=None,
        gateway_profile=profile,
        environment="ci",
        upstream_provider="mock",
        upstream_base_url="http://mock-upstream",
        upstream_api_key=FAKE_UPSTREAM_KEY,
        client_key_hashes=keys["hashes"],
        client_key_pepper=keys["pepper"],
        system_prompt_file=str(ROOT / "app/core/system_prompt.txt"),
        rate_limit_default="10/minute",
        upstream_total_timeout=0.5,
        upstream_read_timeout=0.5,
        circuit_failure_threshold=3,
        log_file=str(log_file),
    )
    base.update(overrides)
    return Settings(**base)


@pytest_asyncio.fixture
async def gateway_factory(keys, tmp_path):
    clients: list[httpx.AsyncClient] = []

    async def _make(profile: str, **overrides):
        # Los logs del perfil seguro se conservan en logs/ para escanearlos con gitleaks
        # (checklist: ninguna key en los logs generados durante las pruebas).
        # Los de baseline filtran a proposito: quedan en un directorio temporal.
        log_file = (ROOT / "logs" / "pytest-secure.log") if profile == "secure" \
            else tmp_path / "gateway-baseline.log"
        settings = make_settings(profile, keys, log_file, **overrides)
        app = create_app(settings, upstream_transport=httpx.ASGITransport(app=mock_app))
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://gateway")
        client.log_file = log_file  # type: ignore[attr-defined]
        clients.append(client)
        return client

    yield _make
    for c in clients:
        await c.aclose()


def chat_body(content: str, role: str = "user") -> dict:
    return {"messages": [{"role": role, "content": content}]}


@pytest.fixture
def evidence(request):
    def _record(category: str, profile: str, data: dict) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        path = EVIDENCE_DIR / f"{category}-{profile}.json"
        data = {"test": request.node.nodeid, "category": category, "profile": profile,
                "recorded_at": datetime.now(timezone.utc).isoformat(), **data}
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    return _record
