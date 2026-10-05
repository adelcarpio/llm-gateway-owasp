"""LLM07 System Prompt Leakage: guardia sobre la salida del modelo.

La respuesta del proveedor es dato NO confiable. Se bloquea si:
  - contiene el canary token (fuga literal inequivoca), o
  - comparte una secuencia de >= K palabras consecutivas con el system prompt.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

NEUTRAL_RESPONSE = "La respuesta no esta disponible por la politica de seguridad del servicio."


@dataclass(frozen=True)
class OutputDecision:
    allowed: bool
    reason: str | None = None  # "canary" | "ngram_overlap"


def _words(text: str) -> list[str]:
    folded = unicodedata.normalize("NFD", text.lower())
    folded = "".join(c for c in folded if unicodedata.category(c) != "Mn")
    return re.findall(r"[a-z0-9]+", folded)


class OutputGuard:
    def __init__(self, system_prompt: str, canary: str, ngram_words: int = 8):
        self._canary = canary
        self._k = ngram_words
        words = _words(system_prompt)
        self._ngrams = {tuple(words[i:i + self._k]) for i in range(max(0, len(words) - self._k + 1))}

    def inspect(self, output: str) -> OutputDecision:
        if self._canary and self._canary in output:
            return OutputDecision(False, "canary")
        words = _words(output)
        for i in range(max(0, len(words) - self._k + 1)):
            if tuple(words[i:i + self._k]) in self._ngrams:
                return OutputDecision(False, "ngram_overlap")
        return OutputDecision(True)
