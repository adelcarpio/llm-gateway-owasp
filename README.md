# LLM Gateway con seguridad OWASP Top 10 for LLM Applications (2025)

Gateway FastAPI que actúa como **único punto de entrada** (`POST /v1/chat`) hacia proveedores LLM
(Anthropic, OpenAI, Ollama o un mock determinista). Implementa y **demuestra en vivo** cuatro mitigaciones OWASP:
**LLM10**, **LLM01**, **LLM02** y **LLM07**, además de degradación controlada ante fallos upstream.

> Proyecto final · Fundamentos de Arquitectura de LLMs · Opción 4.
> Mapeo completo y procedimiento de evidencia: [`docs/OWASP_MAPPING.md`](docs/OWASP_MAPPING.md).

## Arquitectura

```
cliente ──POST /v1/chat──▶ 1 Auth (HMAC) → 2 Cuota por client_id (LLM10) → 3 Esquema (sin rol system)
                          → 4 Sanitización (LLM01) → 5 Prompt + canary (LLM07) → 6 Adaptador (único con la key)
                          ──▶ proveedor ──▶ 7 Guardia de salida (LLM07) → 8 Auditoría allowlist (LLM02) ──▶ cliente
```

| Ruta | Responsabilidad |
| --- | --- |
| `app/api/chat.py` | Endpoint único y orquestación del pipeline |
| `app/security/` | `auth.py`, `rate_limit.py`, `sanitizer.py`, `output_guard.py` (un módulo por control) |
| `app/providers/clients.py` | Adaptadores; único módulo que lee la credencial upstream |
| `app/resilience/` | Taxonomía de errores RFC 9457 y circuit breaker |
| `app/observability/secure_logger.py` | Evento de auditoría por allowlist + redacción |
| `mock_upstream/app.py` | Proveedor simulado vulnerable y determinista, con fallos inyectables |
| `attacks/` | Ataques reproducibles con `curl` |
| `tests/` | Unitarias, seguridad antes/después en ambos perfiles, resiliencia |

## Perfiles `baseline` y `secure`

El mismo binario corre en dos perfiles definidos en `.env.profile` (lo escribe `scripts/switch_profile.sh`):

- `baseline`: todos los controles desactivados, para reproducir cada ataque (línea base).
- `secure`: todos los controles activos.

El arranque **aborta** si `ENVIRONMENT=production` y cualquier control está desactivado.

## Inicio rápido

Requisitos: Python 3.12, `make`, `curl`, `jq`; Docker opcional; [gitleaks](https://github.com/gitleaks/gitleaks#installing) recomendado.

```bash
make bootstrap          # genera .env, .env.profile y .demo_keys (gitignored)
source .demo_keys       # exporta DEMO_CLIENT_KEY_A y DEMO_CLIENT_KEY_B
make install            # dependencias + hook pre-commit de gitleaks
make test               # 51 pruebas
```

**Con Docker** (gateway + mock + Redis):

```bash
docker compose up -d --build
make attack-llm10 PROFILE=baseline   # luego PROFILE=secure
make attack-llm01 PROFILE=baseline
make attack-llm02 PROFILE=baseline
make attack-llm07 PROFILE=baseline
make attack-upstream PROFILE=secure
make logs                            # auditoría en vivo (otra terminal)
```

**Sin Docker**: `make demo-local` levanta mock y gateway con uvicorn y ejecuta cada ataque antes y después.

Después de cualquier demo en `baseline` ejecuta `make clean-logs`. El log de la línea base contiene, a propósito, la credencial ficticia.

## Usar un proveedor real

En `.env`:

```bash
UPSTREAM_PROVIDER=anthropic           # o openai | ollama
UPSTREAM_BASE_URL=https://api.anthropic.com
UPSTREAM_MODEL=<modelo>
UPSTREAM_API_KEY=<tu key>             # en despliegue: Azure Key Vault / variables del orquestador
```

Con Docker exporta además `DOCKER_UPSTREAM_BASE_URL`. La evidencia oficial usa el mock porque un modelo real es no determinista.

## Comandos

`make help` lista todos: `bootstrap`, `up`, `down`, `run`, `run-mock`, `baseline`, `secure`, `reset`, `mock-mode`,
`test`, `evidence`, `report`, `attack-*`, `attacks-all`, `demo-local`, `scan`, `clean-logs`.

## Seguridad del repositorio

- `.env`, `.env.profile`, `.demo_keys`, `logs/` y `evidence/` están en `.gitignore`.
- `gitleaks` corre en pre-commit y en CI sobre el **historial completo**, con reglas propias para keys de Anthropic y del gateway (`.gitleaks.toml`).
- CI ejecuta la suite y escanea los logs que genera el perfil seguro.
