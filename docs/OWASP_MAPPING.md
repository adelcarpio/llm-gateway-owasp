# Mapeo OWASP Top 10 for LLM Applications (2025) → mitigación → evidencia

Cada fila se reproduce con un comando y define qué se observa **sin** (`baseline`) y **con** (`secure`) la protección.
El mismo código corre en ambos perfiles; solo cambia la configuración (`.env.profile`).
La evidencia automatizada se genera con `make evidence` en `evidence/<fecha>/*.json` y `evidence/REPORT.md`.

## Matriz

| OWASP | Mitigación (módulo) | Reproducir en vivo | Test automatizado | Sin protección | Con protección |
| --- | --- | --- | --- | --- | --- |
| **LLM10** Unbounded Consumption | Cuota por `client_id` derivado de la key (no por IP), tope de cuerpo y de `max_tokens` · `app/security/rate_limit.py` | `make attack-llm10 PROFILE=baseline\|secure` | `tests/security/test_llm10_rate_limit.py` | 15/15 respuestas `200`; 15 llamadas al proveedor; rotar IP irrelevante | 10 `200` + 5 `429` con `Retry-After`; 10 llamadas al proveedor; rotar IP no evade; el cliente B conserva su cuota |
| **LLM01** Prompt Injection | Aislamiento de roles (esquema), normalización Unicode, reglas `INJ-*`, spotlighting · `app/security/sanitizer.py`, `app/api/schemas.py`, `app/core/prompt_builder.py` | `make attack-llm01 PROFILE=…` | `tests/security/test_llm01_prompt_injection.py`, `tests/unit/test_sanitizer.py` | Respuesta `PWNED`; el mock registra la llamada; `role=system` aceptado | `400 INPUT_REJECTED`; **0** llamadas al proveedor; log con `rule_id` y sin payload; `role=system` → `422` |
| **LLM02** Sensitive Information Disclosure | `SecretStr`, keys de cliente como HMAC, logger por allowlist + redacción, errores RFC 9457, `gitleaks` en pre-commit y CI · `app/config.py`, `app/security/auth.py`, `app/observability/secure_logger.py` | `make attack-llm02 PROFILE=…` | `tests/security/test_llm02_sensitive_info.py`, `tests/unit/test_logging_and_config.py` | `500` con `Traceback` y URL del proveedor; log con `Authorization`, key de cliente y DNI; `gitleaks`: 4 hallazgos | `502 UPSTREAM_UNAVAILABLE` sin traza; log sin credenciales ni PII; `gitleaks`: 0 hallazgos; alerta al operador |
| **LLM07** System Prompt Leakage | Canary token en el system prompt + detección de solapamiento de 8 palabras en la salida · `app/security/output_guard.py` | `make attack-llm07 PROFILE=…` (en `secure` desactiva el sanitizador para aislar la guardia) | `tests/security/test_llm07_system_prompt_leak.py`, `tests/unit/test_output_guard.py` | La respuesta contiene el system prompt y `CANARY-…` | Respuesta neutra `OUTPUT_FILTERED`; log `blocked_output_leak` sin el fragmento ni el canary |
| Requisito no funcional: degradación controlada | Timeouts, reintentos acotados con backoff (solo 429/503), circuit breaker, taxonomía de errores · `app/providers/clients.py`, `app/resilience/` | `make attack-upstream PROFILE=…` | `tests/resilience/test_upstream_failures.py` | `500` con traza; en timeout el cliente queda esperando | `504`/`502`/`503` tipados en `application/problem+json`; circuito abierto tras 3 fallos |

## Qué NO se registra y por qué

| Dato excluido | Razón | Sustituto auditable |
| --- | --- | --- |
| Prompt y respuesta | Pueden contener PII o datos corporativos; el log tendría controles más débiles que la app | `prompt_chars`, `tokens_in`, `tokens_out` |
| API keys y cabeceras `Authorization` / `X-Gateway-Key` | Un log filtrado sería una credencial filtrada | `client_id` = `cli_` + prefijo del HMAC |
| System prompt y canary | Su exposición es el riesgo LLM07 | `outcome=blocked_output_leak` |
| Fragmento que disparó una regla | Reproduciría el payload malicioso | `rule_id` |
| Trazas en la respuesta al cliente | Revelan rutas, librerías y proveedor | `request_id` para correlacionar |
| Hash plano del prompt | Reversible por fuerza bruta con prompts cortos | No se registra |

La garantía es estructural: `AuditEvent` declara `extra="forbid"`, así que un campo no declarado no puede escribirse.
La redacción por patrones (`RedactionFilter`) es una segunda barrera.

## Reproducción por un tercero

```bash
git clone https://github.com/adelcarpio/llm-gateway-owasp.git && cd llm-gateway-owasp
make bootstrap && source .demo_keys
make install          # dependencias + hook de gitleaks
make test             # 51 pruebas: unitarias, antes/después y resiliencia
make evidence         # JSON por categoría y perfil + evidence/REPORT.md
docker compose up -d --build && make attacks-all     # o: make demo-local (sin Docker)
make scan             # gitleaks: historial git completo + logs/
make clean-logs       # obligatorio tras demos en baseline
```

## Limitaciones reconocidas

- La detección heurística de injection es evadible con paráfrasis, otros idiomas o codificaciones. Por eso es una de cuatro capas, y LLM07 actúa como segunda línea en la salida.
- La detección de fuga por solapamiento literal no detecta paráfrasis del system prompt. Por diseño, el system prompt no contiene secretos.
- Sin streaming: la guardia de salida necesita la respuesta completa.
- El mock es determinista a propósito. Contra un modelo real (`UPSTREAM_PROVIDER=anthropic|openai|ollama`), LLM01 y LLM07 pueden variar entre ejecuciones.
