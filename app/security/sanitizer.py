"""LLM01 Prompt Injection: sanitizacion de la entrada antes de construir el prompt.

Funcion pura y testeable en aislamiento. Capas:
  1. Normalizacion Unicode NFKC.
  2. Eliminacion de caracteres invisibles y de control (ancho cero, bidi, etc.).
  3. Deteccion heuristica con reglas versionadas (INJ-xxx).
La heuristica es evadible por parafrasis: por eso es UNA capa entre varias
(aislamiento de roles, spotlighting y guardia de salida LLM07).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_ALLOWED_CONTROL = {"\n", "\t"}

# Reglas: (id, descripcion, patron). Patrones sobre texto normalizado y en minusculas.
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("INJ-001", "Anulacion de instrucciones previas",
     re.compile(r"\b(ignora|olvida|omite|descarta|ignore|forget|disregard)\b.{0,40}\b(instrucciones|indicaciones|reglas|instructions|rules|prompt)\b")),
    ("INJ-002", "Solicitud de revelar el prompt de sistema",
     re.compile(r"\b(system prompt|prompt (de|del) sistema|instrucciones (iniciales|del sistema|ocultas)|initial instructions|hidden instructions)\b")),
    ("INJ-003", "Tokens de plantilla de chat",
     re.compile(r"(<\|im_start\|>|<\|im_end\|>|\[/?inst\]|<<sys>>|###\s*(system|sistema)\s*:|<\|system\|>)")),
    ("INJ-004", "Cambio de rol o persona sin restricciones",
     re.compile(r"\b(ahora eres|a partir de ahora eres|act[uú]a como|you are now|act as)\b.{0,40}\b(sin restricciones|sin filtros|dan|jailbreak|unrestricted|no restrictions)\b")),
    ("INJ-005", "Modo desarrollador / jailbreak",
     re.compile(r"\b(developer mode|modo desarrollador|jailbreak|do anything now)\b")),
]


@dataclass(frozen=True)
class SanitizationResult:
    allowed: bool
    normalized_text: str
    rule_id: str | None = None
    removed_chars: int = 0


def normalize(text: str) -> tuple[str, int]:
    nfkc = unicodedata.normalize("NFKC", text)
    kept: list[str] = []
    removed = 0
    for ch in nfkc:
        cat = unicodedata.category(ch)
        if (cat in ("Cf", "Cc", "Co", "Cs") and ch not in _ALLOWED_CONTROL):
            removed += 1
            continue
        kept.append(ch)
    collapsed = re.sub(r"[ \u00a0]{2,}", " ", "".join(kept))
    return collapsed, removed


def _fold(text: str) -> str:
    """Minusculas y sin tildes, solo para comparar contra las reglas."""
    decomposed = unicodedata.normalize("NFD", text.lower())
    return "".join(c for c in decomposed if unicodedata.category(c) != "Mn")


def sanitize(text: str, max_chars: int | None = None) -> SanitizationResult:
    normalized, removed = normalize(text)
    if max_chars is not None and len(normalized) > max_chars:
        return SanitizationResult(False, normalized, "LEN-001", removed)
    folded = _fold(normalized)
    for rule_id, _desc, pattern in RULES:
        if pattern.search(folded):
            return SanitizationResult(False, normalized, rule_id, removed)
    return SanitizationResult(True, normalized, None, removed)
