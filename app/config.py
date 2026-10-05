"""Configuracion del gateway.

Principios:
- Los secretos son SecretStr: nunca aparecen en repr(), str() ni en logs.
- El perfil `baseline` desactiva los controles para reproducir ataques (linea base).
- El perfil `baseline` NO puede arrancar en produccion (fail-closed).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", ".env.profile"), env_file_encoding="utf-8", extra="ignore")

    # --- Perfil y entorno ---------------------------------------------------
    gateway_profile: Literal["baseline", "secure"] = "secure"
    environment: Literal["local", "ci", "production"] = "local"

    # Flags individuales. None = hereda del perfil (secure -> True, baseline -> False).
    sec_rate_limit_enabled: bool | None = None
    sec_sanitizer_enabled: bool | None = None
    sec_output_guard_enabled: bool | None = None
    sec_safe_logging_enabled: bool | None = None
    sec_safe_errors_enabled: bool | None = None

    # --- LLM10: consumo ------------------------------------------------------
    rate_limit_default: str = "10/minute;200/day"
    rate_limit_storage_uri: str = "memory://"
    max_body_bytes: int = 32_768
    max_input_chars: int = 4_000
    max_messages: int = 20
    max_output_tokens: int = 1_024

    # --- Upstream ------------------------------------------------------------
    upstream_provider: Literal["mock", "openai", "ollama", "anthropic"] = "mock"
    upstream_base_url: str = "http://localhost:9000"
    upstream_model: str = "mock-llm-1"
    upstream_api_key: SecretStr = SecretStr("")
    upstream_connect_timeout: float = 3.0
    upstream_read_timeout: float = 20.0
    upstream_total_timeout: float = 25.0
    upstream_max_retries: int = 2
    circuit_failure_threshold: int = 3
    circuit_cooldown_seconds: float = 30.0

    # --- Identidad de clientes (LLM02) --------------------------------------
    # Formato: "nombre:hmac_hex,nombre2:hmac_hex". Nunca la key en claro.
    client_key_hashes: str = ""
    client_key_pepper: SecretStr = SecretStr("")

    # --- Prompt de sistema (LLM07) -------------------------------------------
    system_prompt_file: str = "app/core/system_prompt.txt"
    canary_token: SecretStr = SecretStr("")  # vacio = se genera al arrancar
    leak_ngram_words: int = Field(default=8, ge=4)

    # --- Logging -------------------------------------------------------------
    log_file: str = "logs/gateway.log"

    # ------------------------------------------------------------------------
    def _flag(self, value: bool | None) -> bool:
        return (self.gateway_profile == "secure") if value is None else value

    @property
    def rate_limit_on(self) -> bool:
        return self._flag(self.sec_rate_limit_enabled)

    @property
    def sanitizer_on(self) -> bool:
        return self._flag(self.sec_sanitizer_enabled)

    @property
    def output_guard_on(self) -> bool:
        return self._flag(self.sec_output_guard_enabled)

    @property
    def safe_logging_on(self) -> bool:
        return self._flag(self.sec_safe_logging_enabled)

    @property
    def safe_errors_on(self) -> bool:
        return self._flag(self.sec_safe_errors_enabled)

    @model_validator(mode="after")
    def _production_guard(self) -> "Settings":
        if self.environment == "production":
            disabled = [
                name for name, on in {
                    "rate_limit": self.rate_limit_on,
                    "sanitizer": self.sanitizer_on,
                    "output_guard": self.output_guard_on,
                    "safe_logging": self.safe_logging_on,
                    "safe_errors": self.safe_errors_on,
                }.items() if not on
            ]
            if disabled:
                raise ValueError(
                    f"Arranque abortado: controles desactivados en produccion: {disabled}"
                )
            if not self.client_key_pepper.get_secret_value():
                raise ValueError("Arranque abortado: CLIENT_KEY_PEPPER vacio en produccion")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
