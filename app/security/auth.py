"""Autenticacion de clientes del gateway (LLM02 / LLM10).

- Las keys de cliente se almacenan como HMAC-SHA256(pepper, key): nunca en claro.
- La comparacion es en tiempo constante.
- El client_id que se usa para cuotas y logs es un seudonimo derivado del HMAC.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from app.config import Settings


@dataclass(frozen=True)
class ClientIdentity:
    name: str
    client_id: str  # seudonimo estable, apto para logs


def hash_key(pepper: str, key: str) -> str:
    return hmac.new(pepper.encode(), key.encode(), hashlib.sha256).hexdigest()


class ClientRegistry:
    def __init__(self, settings: Settings):
        self._pepper = settings.client_key_pepper.get_secret_value()
        self._entries: list[tuple[str, str]] = []
        for item in filter(None, (p.strip() for p in settings.client_key_hashes.split(","))):
            name, _, digest = item.partition(":")
            if name and len(digest) == 64:
                self._entries.append((name, digest.lower()))

    def authenticate(self, presented_key: str | None) -> ClientIdentity | None:
        if not presented_key or not self._pepper:
            return None
        candidate = hash_key(self._pepper, presented_key)
        match: ClientIdentity | None = None
        # Recorre todas las entradas para no filtrar informacion por tiempo.
        for name, digest in self._entries:
            if hmac.compare_digest(candidate, digest):
                match = ClientIdentity(name=name, client_id=f"cli_{digest[:8]}")
        return match
