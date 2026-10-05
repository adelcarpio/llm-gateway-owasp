"""Adaptadores de proveedor. UNICO modulo que lee la credencial upstream.

- `OpenAICompatibleProvider`: OpenAI, Ollama (/v1) y el mock del proyecto.
- `AnthropicProvider`: Messages API.
En perfil seguro: timeouts, reintentos acotados (solo 429/503) y circuit breaker.
En perfil baseline: llamada ingenua (sin timeouts, raise_for_status), para la linea base.
"""
from __future__ import annotations

import asyncio
import logging
import random

import httpx

from app.config import Settings
from app.providers.base import ProviderResult
from app.resilience.circuit_breaker import CircuitBreaker
from app.resilience.errors import (CircuitOpen, UpstreamAuthError, UpstreamError,
                                   UpstreamSaturated, UpstreamTimeout)

naive_log = logging.getLogger("gateway.naive")


class _BaseProvider:
    name = "base"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.hardened = settings.safe_errors_on
        timeout = (httpx.Timeout(settings.upstream_read_timeout, connect=settings.upstream_connect_timeout)
                   if self.hardened else httpx.Timeout(None))
        self._client = httpx.AsyncClient(base_url=settings.upstream_base_url, timeout=timeout,
                                         transport=transport)
        self.breaker = CircuitBreaker(settings.circuit_failure_threshold,
                                      settings.circuit_cooldown_seconds)

    # --- a implementar por cada proveedor -----------------------------------
    def _request(self, system: str, messages: list[dict[str, str]], max_tokens: int) -> tuple[str, dict, dict]:
        raise NotImplementedError

    def _parse(self, data: dict) -> ProviderResult:
        raise NotImplementedError

    # ------------------------------------------------------------------------
    async def complete(self, system: str, messages: list[dict[str, str]], max_tokens: int) -> ProviderResult:
        path, headers, body = self._request(system, messages, max_tokens)
        if not self.hardened:
            return await self._naive_call(path, headers, body)
        return await self._hardened_call(path, headers, body)

    async def _naive_call(self, path: str, headers: dict, body: dict) -> ProviderResult:
        # LINEA BASE VULNERABLE (LLM02): registra cabeceras con la credencial.
        naive_log.info("llamando upstream %s headers=%s body=%s", path, headers, body)
        resp = await self._client.post(path, headers=headers, json=body)
        resp.raise_for_status()
        return self._parse(resp.json())

    async def _hardened_call(self, path: str, headers: dict, body: dict) -> ProviderResult:
        if not self.breaker.allow():
            raise CircuitOpen()
        attempts = self.settings.upstream_max_retries + 1
        for attempt in range(attempts):
            try:
                resp = await asyncio.wait_for(self._client.post(path, headers=headers, json=body),
                                              timeout=self.settings.upstream_total_timeout)
            except (asyncio.TimeoutError, httpx.TimeoutException):
                self.breaker.record_failure()
                raise UpstreamTimeout() from None
            except httpx.HTTPError:
                self.breaker.record_failure()
                raise UpstreamError() from None

            if resp.status_code in (429, 503) and attempt < attempts - 1:
                await asyncio.sleep(min(2.0, 0.2 * 2 ** attempt) + random.uniform(0, 0.1))
                continue
            if resp.status_code in (401, 403):
                self.breaker.record_failure()
                raise UpstreamAuthError() from None
            if resp.status_code == 429:
                raise UpstreamSaturated()
            if resp.status_code >= 500:
                self.breaker.record_failure()
                raise UpstreamError()
            if resp.status_code >= 400:
                raise UpstreamError()
            try:
                result = self._parse(resp.json())
            except (ValueError, KeyError, TypeError, IndexError):
                self.breaker.record_failure()
                raise UpstreamError() from None
            self.breaker.record_success()
            return result
        raise UpstreamSaturated()

    async def aclose(self) -> None:
        await self._client.aclose()


class OpenAICompatibleProvider(_BaseProvider):
    name = "openai-compatible"

    def _request(self, system, messages, max_tokens):
        headers = {"Authorization": f"Bearer {self.settings.upstream_api_key.get_secret_value()}"}
        body = {"model": self.settings.upstream_model,
                "messages": [{"role": "system", "content": system}, *messages],
                "max_tokens": max_tokens}
        return "/v1/chat/completions", headers, body

    def _parse(self, data):
        usage = data.get("usage") or {}
        return ProviderResult(text=data["choices"][0]["message"]["content"],
                              model=data.get("model", self.settings.upstream_model),
                              tokens_in=usage.get("prompt_tokens"),
                              tokens_out=usage.get("completion_tokens"))


class AnthropicProvider(_BaseProvider):
    name = "anthropic"

    def _request(self, system, messages, max_tokens):
        headers = {"x-api-key": self.settings.upstream_api_key.get_secret_value(),
                   "anthropic-version": "2023-06-01"}
        body = {"model": self.settings.upstream_model, "system": system,
                "messages": messages, "max_tokens": max_tokens}
        return "/v1/messages", headers, body

    def _parse(self, data):
        text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        usage = data.get("usage") or {}
        return ProviderResult(text=text, model=data.get("model", self.settings.upstream_model),
                              tokens_in=usage.get("input_tokens"),
                              tokens_out=usage.get("output_tokens"))


def build_provider(settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
    if settings.upstream_provider == "anthropic":
        return AnthropicProvider(settings, transport)
    return OpenAICompatibleProvider(settings, transport)
