"""Proveedor LLM simulado y determinista (API compatible con OpenAI).

Simula un modelo VULNERABLE para que la evidencia sea reproducible:
  - Obedece instrucciones de anulacion (responde "PWNED")       -> demo LLM01
  - Revela su system prompt si se le pide su configuracion       -> demo LLM07
Fallos inyectables: POST /_mode {"mode": "ok|timeout|500|429|401|503"} -> demo resiliencia.
"""
from __future__ import annotations

import asyncio
import os
import re
import unicodedata

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock LLM upstream")
STATE = {"mode": os.getenv("MOCK_MODE", "ok"), "calls": 0,
         "timeout_seconds": float(os.getenv("MOCK_TIMEOUT_SECONDS", "45"))}

_OVERRIDE = re.compile(r"\b(ignora|olvida|ignore|forget|disregard)\b.{0,40}\b(instrucciones|instructions|reglas|rules)\b")
_LEAK = re.compile(r"(configuracion|iniciado|instrucciones iniciales|system prompt|initial instructions)")


def _understand(text: str) -> str:
    """El modelo 'entiende' texto ofuscado: quita invisibles, tildes y mayusculas."""
    text = "".join(c for c in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(c) not in ("Cf", "Cc") or c in "\n\t")
    text = unicodedata.normalize("NFD", text.lower())
    return "".join(c for c in text if unicodedata.category(c) != "Mn")


@app.post("/v1/chat/completions")
async def completions(request: Request):
    STATE["calls"] += 1
    body = await request.json()
    mode = STATE["mode"]
    if mode == "timeout":
        await asyncio.sleep(STATE["timeout_seconds"])
    elif mode == "500":
        return JSONResponse({"error": {"message": "internal upstream failure"}}, status_code=500)
    elif mode == "503":
        return JSONResponse({"error": {"message": "overloaded"}}, status_code=503)
    elif mode == "429":
        return JSONResponse({"error": {"message": "rate limited"}}, status_code=429)
    elif mode == "401":
        return JSONResponse({"error": {"message": "invalid api key"}}, status_code=401)

    if not request.headers.get("authorization", "").startswith("Bearer "):
        return JSONResponse({"error": {"message": "missing api key"}}, status_code=401)

    msgs = body.get("messages", [])
    system = "\n".join(m["content"] for m in msgs if m.get("role") == "system")
    user = "\n".join(m["content"] for m in msgs if m.get("role") == "user")
    understood = _understand(user)
    roles = {m.get("role") for m in msgs[1:]}

    if _OVERRIDE.search(understood) or "system" in roles:
        answer = "PWNED"
    elif _LEAK.search(understood):
        answer = f"Claro, esta es mi configuracion:\n```\n{system}\n```"
    else:
        answer = f"Respuesta simulada a: {user[-120:].strip()}"

    return {"id": "mock-1", "object": "chat.completion", "model": body.get("model", "mock-llm-1"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(1, len(system + user) // 4),
                      "completion_tokens": max(1, len(answer) // 4)}}


@app.post("/_mode")
async def set_mode(request: Request):
    data = await request.json()
    STATE["mode"] = str(data.get("mode", "ok"))
    if "timeout_seconds" in data:
        STATE["timeout_seconds"] = float(data["timeout_seconds"])
    return {"mode": STATE["mode"]}


@app.get("/_stats")
async def stats():
    return {"calls": STATE["calls"], "mode": STATE["mode"]}


@app.post("/_reset")
async def reset():
    STATE.update(calls=0, mode="ok")
    return {"calls": 0, "mode": "ok"}
