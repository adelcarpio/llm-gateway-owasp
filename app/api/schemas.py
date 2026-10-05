from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictMessage(BaseModel):
    """Perfil seguro: el cliente NO puede enviar rol `system` (LLM01)."""
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=20_000)


class StrictChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    messages: list[StrictMessage] = Field(min_length=1)
    max_tokens: int | None = Field(default=None, ge=1)


class LaxMessage(BaseModel):
    """Linea base vulnerable: acepta cualquier rol, incluido `system`."""
    role: str
    content: str


class LaxChatRequest(BaseModel):
    messages: list[LaxMessage] = Field(min_length=1)
    max_tokens: int | None = None
