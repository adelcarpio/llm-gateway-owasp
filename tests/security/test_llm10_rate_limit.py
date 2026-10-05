"""LLM10 Unbounded Consumption: rafaga con la misma key rotando la IP de origen."""
import pytest

from mock_upstream.app import STATE as MOCK
from tests.conftest import chat_body

BURST = 15  # limite configurado: 10/minute


async def burst(client, key):
    codes = []
    for i in range(1, BURST + 1):
        r = await client.post("/v1/chat", json=chat_body("Resume en una linea que es un gateway"),
                              headers={"X-Gateway-Key": key, "X-Forwarded-For": f"203.0.113.{i}"})
        codes.append(r.status_code)
    return codes, r


async def test_baseline_burst_is_not_limited(gateway_factory, keys, evidence):
    gw = await gateway_factory("baseline")
    codes, _ = await burst(gw, keys["A"])
    evidence("LLM10", "baseline", {"status_codes": codes, "upstream_calls": MOCK["calls"]})
    assert codes == [200] * BURST            # el ataque tiene exito
    assert MOCK["calls"] == BURST


async def test_secure_burst_is_limited_per_key_not_per_ip(gateway_factory, keys, evidence):
    gw = await gateway_factory("secure")
    codes, last = await burst(gw, keys["A"])
    calls_after_burst = MOCK["calls"]
    other = await gw.post("/v1/chat", json=chat_body("Hola"), headers={"X-Gateway-Key": keys["B"]})
    evidence("LLM10", "secure", {"status_codes": codes, "upstream_calls": calls_after_burst,
                                 "retry_after": last.headers.get("retry-after"),
                                 "other_client_status": other.status_code,
                                 "other_client_remaining": other.headers.get("x-ratelimit-remaining")})
    assert codes == [200] * 10 + [429] * 5  # rotar IP no evade el limite
    assert calls_after_burst == 10
    assert last.json()["code"] == "RATE_LIMITED"
    assert int(last.headers["retry-after"]) > 0
    assert other.status_code == 200 and other.headers["x-ratelimit-remaining"] == "9"


@pytest.mark.parametrize("profile,expected", [("baseline", 200), ("secure", 413)])
async def test_oversized_body(gateway_factory, keys, profile, expected):
    gw = await gateway_factory(profile)
    r = await gw.post("/v1/chat", json=chat_body("a" * 40_000), headers={"X-Gateway-Key": keys["A"]})
    assert r.status_code == expected
