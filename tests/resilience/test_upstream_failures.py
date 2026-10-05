"""Requisito no funcional: degradacion controlada ante fallos upstream."""
import time

import pytest

from mock_upstream.app import STATE as MOCK
from tests.conftest import chat_body


@pytest.mark.parametrize("mode,status,code", [
    ("timeout", 504, "UPSTREAM_TIMEOUT"),
    ("500", 502, "UPSTREAM_UNAVAILABLE"),
    ("429", 503, "UPSTREAM_SATURATED"),
    ("401", 502, "UPSTREAM_UNAVAILABLE"),
])
async def test_secure_maps_failures(gateway_factory, keys, evidence, mode, status, code):
    gw = await gateway_factory("secure")
    MOCK["mode"] = mode
    t0 = time.perf_counter()
    r = await gw.post("/v1/chat", json=chat_body("Hola"), headers={"X-Gateway-Key": keys["A"]})
    elapsed = time.perf_counter() - t0
    evidence(f"RESILIENCIA-{mode}", "secure", {"status": r.status_code, "body": r.json(),
                                                "elapsed_s": round(elapsed, 2)})
    assert r.status_code == status and r.json()["code"] == code
    assert "Traceback" not in r.text and "mock-upstream" not in r.text
    assert elapsed < 2.0


@pytest.mark.parametrize("mode", ["500", "429"])
async def test_baseline_exposes_trace(gateway_factory, keys, evidence, mode):
    gw = await gateway_factory("baseline")
    MOCK["mode"] = mode
    r = await gw.post("/v1/chat", json=chat_body("Hola"), headers={"X-Gateway-Key": keys["A"]})
    evidence(f"RESILIENCIA-{mode}", "baseline", {"status": r.status_code,
                                                  "trace_exposed": "Traceback" in r.text})
    assert r.status_code == 500 and "Traceback" in r.text


async def test_baseline_timeout_hangs_client(gateway_factory, keys):
    gw = await gateway_factory("baseline")
    MOCK["mode"] = "timeout"
    t0 = time.perf_counter()
    await gw.post("/v1/chat", json=chat_body("Hola"), headers={"X-Gateway-Key": keys["A"]})
    assert time.perf_counter() - t0 >= MOCK["timeout_seconds"]  # sin timeout: el cliente espera


async def test_circuit_breaker_opens(gateway_factory, keys, evidence):
    gw = await gateway_factory("secure")
    MOCK["mode"] = "500"
    codes = []
    for _ in range(6):
        r = await gw.post("/v1/chat", json=chat_body("Hola"), headers={"X-Gateway-Key": keys["A"]})
        codes.append(r.json()["code"])
    evidence("RESILIENCIA-circuit", "secure", {"codes": codes, "upstream_calls": MOCK["calls"]})
    assert codes[:3] == ["UPSTREAM_UNAVAILABLE"] * 3
    assert codes[3:] == ["CIRCUIT_OPEN"] * 3
    assert MOCK["calls"] == 3                       # ya no se castiga al proveedor caido
