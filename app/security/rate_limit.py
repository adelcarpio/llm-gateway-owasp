"""LLM10 Unbounded Consumption: cuota por identidad de cliente.

Usa `limits` (el motor sobre el que esta construido slowapi) con ventana deslizante.
La clave de la cuota es el client_id derivado de la API key, NUNCA la IP:
rotar X-Forwarded-For no evade el limite.
Con REDIS (redis://...) el contador es global entre workers e instancias.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass

from limits import parse_many
from limits.storage import storage_from_string
from limits.strategies import MovingWindowRateLimiter


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class ClientRateLimiter:
    def __init__(self, spec: str, storage_uri: str):
        self._limits = parse_many(spec)
        self._storage = storage_from_string(storage_uri)
        self._limiter = MovingWindowRateLimiter(self._storage)

    def hit(self, client_id: str) -> RateDecision:
        tightest: RateDecision | None = None
        for item in self._limits:
            if not self._limiter.hit(item, "gw", client_id):
                reset_at, _ = self._limiter.get_window_stats(item, "gw", client_id)
                return RateDecision(False, item.amount, 0, max(1, math.ceil(reset_at - time.time())))
            reset_at, remaining = self._limiter.get_window_stats(item, "gw", client_id)
            decision = RateDecision(True, item.amount, remaining,
                                    max(0, math.ceil(reset_at - time.time())))
            if tightest is None or decision.remaining < tightest.remaining:
                tightest = decision
        return tightest or RateDecision(True, 0, 0, 0)

    def reset(self) -> None:
        self._storage.reset()
