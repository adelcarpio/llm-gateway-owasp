from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ProviderResult:
    text: str
    model: str
    tokens_in: int | None
    tokens_out: int | None


class Provider(Protocol):
    name: str

    async def complete(self, system: str, messages: list[dict[str, str]],
                       max_tokens: int) -> ProviderResult: ...
